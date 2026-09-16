rule TTP_XOR_WriteProcessMemory_ef11 {
  strings:
    $key_ef11 = { b8 63 [2] 8a 41 [2] 8c 74 [2] a2 74 [2] 9d 68 }

  condition:
    any of them
}