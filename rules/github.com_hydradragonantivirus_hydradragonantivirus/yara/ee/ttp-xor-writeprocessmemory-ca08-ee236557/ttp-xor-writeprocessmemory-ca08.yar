rule TTP_XOR_WriteProcessMemory_ca08 {
  strings:
    $key_ca08 = { 9d 7a [2] af 58 [2] a9 6d [2] 87 6d [2] b8 71 }

  condition:
    any of them
}