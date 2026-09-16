rule TTP_XOR_WriteProcessMemory_ad4c {
  strings:
    $key_ad4c = { fa 3e [2] c8 1c [2] ce 29 [2] e0 29 [2] df 35 }

  condition:
    any of them
}