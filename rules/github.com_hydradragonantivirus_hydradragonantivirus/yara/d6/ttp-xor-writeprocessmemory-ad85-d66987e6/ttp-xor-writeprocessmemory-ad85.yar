rule TTP_XOR_WriteProcessMemory_ad85 {
  strings:
    $key_ad85 = { fa f7 [2] c8 d5 [2] ce e0 [2] e0 e0 [2] df fc }

  condition:
    any of them
}