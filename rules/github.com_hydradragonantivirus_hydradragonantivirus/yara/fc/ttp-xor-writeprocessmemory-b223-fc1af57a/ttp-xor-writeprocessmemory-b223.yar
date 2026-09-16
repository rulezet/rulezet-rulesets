rule TTP_XOR_WriteProcessMemory_b223 {
  strings:
    $key_b223 = { e5 51 [2] d7 73 [2] d1 46 [2] ff 46 [2] c0 5a }

  condition:
    any of them
}