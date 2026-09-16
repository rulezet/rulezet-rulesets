rule TTP_XOR_WriteProcessMemory_cb89 {
  strings:
    $key_cb89 = { 9c fb [2] ae d9 [2] a8 ec [2] 86 ec [2] b9 f0 }

  condition:
    any of them
}