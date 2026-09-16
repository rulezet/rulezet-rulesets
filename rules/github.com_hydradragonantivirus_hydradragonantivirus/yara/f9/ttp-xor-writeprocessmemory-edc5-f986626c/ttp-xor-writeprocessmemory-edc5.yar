rule TTP_XOR_WriteProcessMemory_edc5 {
  strings:
    $key_edc5 = { ba b7 [2] 88 95 [2] 8e a0 [2] a0 a0 [2] 9f bc }

  condition:
    any of them
}