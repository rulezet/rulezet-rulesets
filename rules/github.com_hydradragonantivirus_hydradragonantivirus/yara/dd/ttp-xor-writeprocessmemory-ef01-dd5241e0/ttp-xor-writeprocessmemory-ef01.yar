rule TTP_XOR_WriteProcessMemory_ef01 {
  strings:
    $key_ef01 = { b8 73 [2] 8a 51 [2] 8c 64 [2] a2 64 [2] 9d 78 }

  condition:
    any of them
}