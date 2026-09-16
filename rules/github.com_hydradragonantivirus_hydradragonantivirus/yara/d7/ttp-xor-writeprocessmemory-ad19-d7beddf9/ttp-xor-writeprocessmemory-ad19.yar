rule TTP_XOR_WriteProcessMemory_ad19 {
  strings:
    $key_ad19 = { fa 6b [2] c8 49 [2] ce 7c [2] e0 7c [2] df 60 }

  condition:
    any of them
}