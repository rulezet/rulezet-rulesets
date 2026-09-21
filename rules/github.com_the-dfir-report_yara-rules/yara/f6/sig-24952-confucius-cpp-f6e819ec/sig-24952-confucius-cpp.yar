import "pe"
rule sig_24952_confucius_cpp {
   meta:
      description = "24952-files - file confucius_cpp.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "dfa8c282178a509346fb0154e6dbd5fbb0b56c38894ce7d244f5ca26d6820e67"
   strings:
      $s1 = "_ZN9confucius5utils7network17LdapQueryExecutor43get_ldap_entry_attributes_processing_resultB5cxx11EP4ldapP7ldapmsgPwRP10bereleme" ascii
      $s2 = "_ZN9confucius5utils7network17LdapQueryExecutor43get_ldap_entry_attributes_processing_resultB5cxx11EP4ldapP7ldapmsgPwRP10bereleme" ascii
      $s3 = "_ZN9confucius5utils7network17LdapQueryExecutor28get_entry_processing_resultsB5cxx11EP4ldapP7ldapmsgS6_RP10berelement" fullword ascii
      $s4 = "C:\\users\\public\\pictures" fullword ascii
      $s5 = "C:\\Users\\public\\pictures" fullword ascii
      $s6 = "_ZN9confucius4core9uploading15UploaderFactory19create_ftp_uploaderERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s7 = "_ZNSt17_Function_handlerIFvvESt5_BindIFZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt1" ascii
      $s8 = "_ZN9confucius4core9uploading11FtpUploaderC2ERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s9 = "_ZN9confucius4core9uploading11FtpUploaderC1ERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s10 = "_ZNSt17_Function_handlerIFvvESt5_BindIFZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt1" ascii
      $s11 = ".data$_ZGVZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12synce" ascii
      $s12 = ".data$_ZGVZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12synce" ascii
      $s13 = ".data$_ZZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12syncedS" ascii
      $s14 = ".data$_ZZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12syncedS" ascii
      $s15 = ".data$_ZN12_GLOBAL__N_110fake_mutexE" fullword ascii
      $s16 = ".data$_ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii
      $s17 = "The default value C:\\users\\public\\pictures will be used" fullword ascii
      $s18 = "_ZN9confucius4core9uploading11FtpUploader23is_file_uploaded2serverERKNSt10filesystem7__cxx114pathE" fullword ascii
      $s19 = "evil_hacker@protonmail.com" fullword ascii
      $s20 = "*St22_Maybe_get_result_typeIZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt10filesystem" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      ( pe.imphash() == "2b2339ccc52edf157788123a8712700d" or 8 of them )
}