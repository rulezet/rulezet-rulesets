rule TTP_XOR_WriteProcessMemory_ef06 {
  strings:
    $key_ef06 = { b8 74 [2] 8a 56 [2] 8c 63 [2] a2 63 [2] 9d 7f }

  condition:
    any of them
}