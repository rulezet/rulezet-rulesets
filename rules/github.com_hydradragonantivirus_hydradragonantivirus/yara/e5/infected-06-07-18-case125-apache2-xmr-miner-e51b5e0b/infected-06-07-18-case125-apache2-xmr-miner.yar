rule infected_06_07_18_case125_apache2_XMR_MINER {
  meta:
    description = "case125 - file apache2"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "3d18f4f503a72a4246b1a13327745fab15f9b34f45e17d4f6e94a311427ad4da"

  strings:
    $x1  = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
    $s2  = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE14_M_get_deleterERKSt9type_info" fullword ascii
    $s3  = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EE6_M_getEv" fullword ascii
    $s4  = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE3getEv" fullword ascii
    $s5  = "_ZN8executor16log_result_errorEONSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
    $s6  = "_ZN8executor16log_socket_errorEONSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
    $s7  = "_ZNSt10__weak_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE9_M_assignEPS0_RKSt14__shared_countILS2_2EE" fullword ascii
    $s8  = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEC4ERKSt10__weak_ptrIS0_LS2_2EESt9nothrow_t" fullword ascii
    $s9  = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
    $s10 = "_ZN8executor15hashrate_reportERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
    $s11 = "get<0, std::__future_base::_State_baseV2::_Make_ready*, std::default_delete<std::__future_base::_State_baseV2::_Make_ready> >" fullword ascii
    $s12 = "get<1, std::__future_base::_State_baseV2::_Make_ready*, std::default_delete<std::__future_base::_State_baseV2::_Make_ready> >" fullword ascii
    $s13 = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EEdeEv" fullword ascii
    $s14 = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EEptEv" fullword ascii
    $s15 = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
    $s16 = "__shared_ptr_access<std::mutex, (__gnu_cxx::_Lock_policy)2, false, false>" fullword ascii
    $s17 = "not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugsbasic_string::_S_create" fullword ascii
    $s18 = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEaSEOS3_" fullword ascii
    $s19 = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEcvbEv" fullword ascii
    $s20 = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE5resetEv" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 5000KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}