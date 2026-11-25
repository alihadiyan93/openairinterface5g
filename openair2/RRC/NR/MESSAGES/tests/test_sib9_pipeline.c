/* SPDX-License-Identifier: LicenseRef-CSSL-1.0 */
#include "test_sib9_fixture.h"

RAN_CONTEXT_t RC;

static bool fail_sib1;
int __real_try_encode_SIB_NR(NR_BCCH_DL_SCH_Message_t *sib, uint8_t *buf, int size);
int __wrap_try_encode_SIB_NR(NR_BCCH_DL_SCH_Message_t *sib, uint8_t *buf, int size)
{
  return fail_sib1 ? -1 : __real_try_encode_SIB_NR(sib, buf, size);
}

static void check_cell(nr_cell_sched_t *cell, uint64_t utc)
{
  NR_COMMON_channels_t *cc = &cell->common_channels;
  NR_BCCH_DL_SCH_Message_t *sib1 = decode_bcch(cc->sib1_bcch_pdu, cc->sib1_bcch_length);
  NR_SI_SchedulingInfo_t *info = sib1->message.choice.c1->choice.systemInformationBlockType1->si_SchedulingInfo;
  AssertFatal(info->schedulingInfoList.list.count == 2, "separate SI windows\n");
  AssertFatal(info->schedulingInfoList.list.array[0]->sib_MappingInfo.list.count == 1
                  && info->schedulingInfoList.list.array[0]->sib_MappingInfo.list.array[0]->type == NR_SIB_TypeInfo__type_sibType2,
              "SIB2 mapping\n");
  AssertFatal(info->schedulingInfoList.list.array[1]->sib_MappingInfo.list.count == 1
                  && info->schedulingInfoList.list.array[1]->sib_MappingInfo.list.array[0]->type == NR_SIB_TypeInfo__type_sibType9,
              "SIB9 mapping\n");
  ASN_STRUCT_FREE(asn_DEF_NR_BCCH_DL_SCH_Message, sib1);
  NR_BCCH_DL_SCH_Message_t *regular = decode_bcch(cc->other_sib_bcch_pdu[0], cc->other_sib_bcch_length[0]);
  NR_SystemInformation_IEs_t *si =
      regular->message.choice.c1->choice.systemInformation->criticalExtensions.choice.systemInformation;
  AssertFatal(si->sib_TypeAndInfo.list.count == 1
                  && si->sib_TypeAndInfo.list.array[0]->choice.sib2->intraFreqCellReselectionInfo.q_RxLevMin == -56,
              "regular sibling preserved\n");
  ASN_STRUCT_FREE(asn_DEF_NR_BCCH_DL_SCH_Message, regular);
  AssertFatal(read_utc(cc->sib9_bcch_pdu, cc->sib9_bcch_length) == utc, "SIB9 UTC\n");
}

static void release_cell(nr_cell_sched_t *cell)
{
  ASN_STRUCT_FREE(asn_DEF_NR_BCCH_DL_SCH_Message, cell->common_channels.sib1);
  ASN_STRUCT_FREE(asn_DEF_NR_SystemInformation_IEs, cell->common_channels.sib9_si);
  memset(cell, 0, sizeof(*cell));
}

int main(void)
{
  logInit();
  nr_cell_sched_t *initial = calloc_or_fail(1, sizeof(*initial));
  initial->common_channels.sib1 = make_sib1(917505);
  uint8_t truncated = 0x5f;
  f1ap_sib_msg_t invalid = {.SI_type = 9, .SI_container = {.buf = &truncated, .len = 1}};
  AssertFatal(nr_mac_configure_other_sib(initial, 1, &invalid) == NR_SI_REJECTED && !initial->common_channels.sib9_si
                  && !initial->common_channels.sib9_bcch_length
                  && !initial->common_channels.sib1->message.choice.c1->choice.systemInformationBlockType1->si_SchedulingInfo,
              "initial rejection cannot advertise SIB9\n");
  release_cell(initial);
  free(initial);
  for (int cycle = 0; cycle < 20; ++cycle) {
    nr_cell_sched_t cells[2] = {0};
    f1ap_setup_resp_t original = {.transaction_id = 1, .rrc_ver = {17, 3, 0}, .num_cells_to_activate = 2};
    original.cells_to_activate = calloc_or_fail(2, sizeof(*original.cells_to_activate));
    for (int c = 0; c < 2; ++c) {
      cells[c].nr_cellid = 917505 + c;
      cells[c].common_channels.sib1 = make_sib1(cells[c].nr_cellid);
      if (c == 1) {
        NR_ServingCellConfigCommon_t *scc = calloc_or_fail(1, sizeof(*scc));
        scc->ext2 = calloc_or_fail(1, sizeof(*scc->ext2));
        scc->ext2->ntn_Config_r17 = calloc_or_fail(1, sizeof(*scc->ext2->ntn_Config_r17));
        scc->ext2->ntn_Config_r17->epochTime_r17 = calloc_or_fail(1, sizeof(NR_EpochTime_r17_t));
        scc->ext2->ntn_Config_r17->epochTime_r17->sfn_r17 = 7;
        cells[c].common_channels.ServingCellConfigCommon = scc;
        seq_arr_t *local = calloc_or_fail(1, sizeof(*local));
        seq_arr_init(local, sizeof(nr_SIBs_t));
        nr_SIBs_t type = {.SIB_type = NR_SIB_19};
        seq_arr_push_back(local, &type, sizeof(type));
        cells[c].common_channels.du_SIBs = local;
      }
      served_cells_to_activate_t *entry = &original.cells_to_activate[c];
      entry->nr_cellid = cells[c].nr_cellid;
      entry->nrpci = 10 + c;
      entry->num_SI = 2;
      entry->plmn = (plmn_id_t){.mcc = 1, .mnc = 1, .mnc_digit_length = 2};
      NR_SIB2_t sibling = {0};
      sibling.intraFreqCellReselectionInfo.q_RxLevMin = -56;
      entry->SI_msg[0] = (f1ap_sib_msg_t){.SI_type = NR_SIB_2, .SI_container = do_SIB2_NR(&sibling)};
      sib9_config_t profile = {.time_info_utc = c ? NR_SIB9_MAX_UTC : 0};
      NR_SIB9_t *sib9 = get_SIB9_NR(&profile);
      entry->SI_msg[1] = (f1ap_sib_msg_t){.SI_type = NR_SIB_9, .SI_container = do_SIB9_NR(sib9)};
      ASN_STRUCT_FREE(asn_DEF_NR_SIB9, sib9);
    }
    F1AP_F1AP_PDU_t *pdu = encode_f1ap_setup_response(&original);
    uint8_t wire[16384];
    asn_enc_rval_t enc = aper_encode_to_buffer(&asn_DEF_F1AP_F1AP_PDU, NULL, pdu, wire, sizeof(wire));
    AssertFatal(enc.encoded > 0, "F1 APER encoding\n");
    ASN_STRUCT_FREE(asn_DEF_F1AP_F1AP_PDU, pdu);
    free_f1ap_setup_response(&original);
    pdu = NULL;
    asn_dec_rval_t dec = aper_decode_complete(NULL, &asn_DEF_F1AP_F1AP_PDU, (void **)&pdu, wire, (enc.encoded + 7) / 8);
    AssertFatal(dec.code == RC_OK, "F1 APER decoding\n");
    f1ap_setup_resp_t received = {0};
    AssertFatal(decode_f1ap_setup_response(pdu, &received) && received.num_cells_to_activate == 2, "F1 response\n");
    ASN_STRUCT_FREE(asn_DEF_F1AP_F1AP_PDU, pdu);
    for (int c = 0; c < 2; ++c) {
      served_cells_to_activate_t *entry = &received.cells_to_activate[c];
      AssertFatal(entry->nr_cellid == cells[c].nr_cellid && entry->num_SI == 2, "cell routing\n");
      AssertFatal(nr_mac_configure_other_sib(&cells[c], entry->num_SI, entry->SI_msg) == NR_SI_PUBLISHED, "publish\n");
      AssertFatal(nr_mac_configure_other_sib(&cells[c], entry->num_SI, entry->SI_msg) == NR_SI_UNCHANGED, "unchanged\n");
      const NR_COMMON_channels_t before = cells[c].common_channels;
      f1ap_sib_msg_t bad[2] = {entry->SI_msg[0], entry->SI_msg[1]};
      bad[1].SI_container.len = 1;
      AssertFatal(nr_mac_configure_other_sib(&cells[c], 2, bad) == NR_SI_REJECTED, "truncated\n");
      uint8_t oversized[NR_SIB9_MAX_BYTES + 1] = {0};
      bad[1] = entry->SI_msg[1];
      bad[1].SI_container = (byte_array_t){.buf = oversized, .len = sizeof(oversized)};
      AssertFatal(nr_mac_configure_other_sib(&cells[c], 2, bad) == NR_SI_REJECTED, "oversized input\n");
      bad[1] = bad[0];
      AssertFatal(nr_mac_configure_other_sib(&cells[c], 2, bad) == NR_SI_REJECTED, "duplicate\n");
      bad[1].SI_type = 5;
      AssertFatal(nr_mac_configure_other_sib(&cells[c], 2, bad) == NR_SI_REJECTED, "unsupported\n");
      fail_sib1 = true;
      AssertFatal(nr_mac_configure_other_sib(&cells[c], entry->num_SI, entry->SI_msg) == NR_SI_REJECTED, "failed SIB1 encode\n");
      fail_sib1 = false;
      AssertFatal(!memcmp(&before, &cells[c].common_channels, sizeof(before)), "rejection changed active snapshot\n");
    }
    free_f1ap_setup_response(&received);
    for (int c = 0; c < 2; ++c) {
      check_cell(&cells[c], c ? NR_SIB9_MAX_UTC : 0);
      if (c == 1) {
        NR_COMMON_channels_t *cc = &cells[c].common_channels;
        NR_BCCH_DL_SCH_Message_t *msg = decode_bcch(cc->other_sib_bcch_pdu[1], cc->other_sib_bcch_length[1]);
        NR_SystemInformation_IEs_t *si =
            msg->message.choice.c1->choice.systemInformation->criticalExtensions.choice.systemInformation;
        AssertFatal(si->sib_TypeAndInfo.list.count == 1
                        && si->sib_TypeAndInfo.list.array[0]->choice.sib19_v1700->ntn_Config_r17->epochTime_r17->sfn_r17 == 7,
                    "SIB19 remains in independent v17 payload\n");
        ASN_STRUCT_FREE(asn_DEF_NR_BCCH_DL_SCH_Message, msg);
        seq_arr_free(cc->du_SIBs, NULL);
        free(cc->du_SIBs);
        cc->du_SIBs = NULL;
        ASN_STRUCT_FREE(asn_DEF_NR_ServingCellConfigCommon, cc->ServingCellConfigCommon);
        cc->ServingCellConfigCommon = NULL;
      }
      AssertFatal(nr_mac_configure_other_sib(&cells[c], 0, NULL) == NR_SI_PUBLISHED, "remove all SI\n");
      AssertFatal(!cells[c].common_channels.sib9_si && !cells[c].common_channels.sib9_bcch_length, "withdraw ownership\n");
      release_cell(&cells[c]);
    }
  }
  logTerm();
  return 0;
}
