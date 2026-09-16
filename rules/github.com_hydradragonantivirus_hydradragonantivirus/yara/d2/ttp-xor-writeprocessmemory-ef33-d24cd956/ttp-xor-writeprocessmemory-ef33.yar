rule TTP_XOR_WriteProcessMemory_ef33 {
  strings:
    $key_ef33 = { b8 41 [2] 8a 63 [2] 8c 56 [2] a2 56 [2] 9d 4a }

  condition:
    any of them
}