rule TTP_XOR_WriteProcessMemory_ab03 {
  strings:
    $key_ab03 = { fc 71 [2] ce 53 [2] c8 66 [2] e6 66 [2] d9 7a }

  condition:
    any of them
}