rule TTP_XOR_WriteProcessMemory_edc0 {
  strings:
    $key_edc0 = { ba b2 [2] 88 90 [2] 8e a5 [2] a0 a5 [2] 9f b9 }

  condition:
    any of them
}