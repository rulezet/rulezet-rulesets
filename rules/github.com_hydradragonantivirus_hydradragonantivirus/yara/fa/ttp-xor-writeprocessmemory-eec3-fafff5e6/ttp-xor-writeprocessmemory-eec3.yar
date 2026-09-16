rule TTP_XOR_WriteProcessMemory_eec3 {
  strings:
    $key_eec3 = { b9 b1 [2] 8b 93 [2] 8d a6 [2] a3 a6 [2] 9c ba }

  condition:
    any of them
}