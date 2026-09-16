rule TTP_XOR_WriteProcessMemory_c538 {
  strings:
    $key_c538 = { 92 4a [2] a0 68 [2] a6 5d [2] 88 5d [2] b7 41 }

  condition:
    any of them
}