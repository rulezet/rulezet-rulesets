rule TTP_XOR_WriteProcessMemory_cc03 {
  strings:
    $key_cc03 = { 9b 71 [2] a9 53 [2] af 66 [2] 81 66 [2] be 7a }

  condition:
    any of them
}