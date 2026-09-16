rule TTP_XOR_WriteProcessMemory_ad39 {
  strings:
    $key_ad39 = { fa 4b [2] c8 69 [2] ce 5c [2] e0 5c [2] df 40 }

  condition:
    any of them
}