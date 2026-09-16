rule TTP_XOR_WriteProcessMemory_b254 {
  strings:
    $key_b254 = { e5 26 [2] d7 04 [2] d1 31 [2] ff 31 [2] c0 2d }

  condition:
    any of them
}