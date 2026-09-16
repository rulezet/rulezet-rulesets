rule TTP_XOR_WriteProcessMemory_cc4d {
  strings:
    $key_cc4d = { 9b 3f [2] a9 1d [2] af 28 [2] 81 28 [2] be 34 }

  condition:
    any of them
}