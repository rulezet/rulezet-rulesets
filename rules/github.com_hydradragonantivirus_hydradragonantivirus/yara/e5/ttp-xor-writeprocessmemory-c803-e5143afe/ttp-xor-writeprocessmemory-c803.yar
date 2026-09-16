rule TTP_XOR_WriteProcessMemory_c803 {
  strings:
    $key_c803 = { 9f 71 [2] ad 53 [2] ab 66 [2] 85 66 [2] ba 7a }

  condition:
    any of them
}