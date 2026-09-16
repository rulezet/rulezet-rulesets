rule TTP_XOR_WriteProcessMemory_e6c3 {
  strings:
    $key_e6c3 = { b1 b1 [2] 83 93 [2] 85 a6 [2] ab a6 [2] 94 ba }

  condition:
    any of them
}