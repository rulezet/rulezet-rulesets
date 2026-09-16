rule TTP_XOR_WriteProcessMemory_cc18 {
  strings:
    $key_cc18 = { 9b 6a [2] a9 48 [2] af 7d [2] 81 7d [2] be 61 }

  condition:
    any of them
}