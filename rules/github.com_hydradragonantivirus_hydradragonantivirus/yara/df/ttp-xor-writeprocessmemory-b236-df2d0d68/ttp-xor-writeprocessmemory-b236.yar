rule TTP_XOR_WriteProcessMemory_b236 {
  strings:
    $key_b236 = { e5 44 [2] d7 66 [2] d1 53 [2] ff 53 [2] c0 4f }

  condition:
    any of them
}