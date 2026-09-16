rule TTP_XOR_WriteProcessMemory_ca36 {
  strings:
    $key_ca36 = { 9d 44 [2] af 66 [2] a9 53 [2] 87 53 [2] b8 4f }

  condition:
    any of them
}