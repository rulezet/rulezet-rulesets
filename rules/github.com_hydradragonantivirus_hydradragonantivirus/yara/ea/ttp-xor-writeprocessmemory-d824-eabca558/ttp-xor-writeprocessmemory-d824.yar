rule TTP_XOR_WriteProcessMemory_d824 {
  strings:
    $key_d824 = { 8f 56 [2] bd 74 [2] bb 41 [2] 95 41 [2] aa 5d }

  condition:
    any of them
}