rule TTP_XOR_WriteProcessMemory_b258 {
  strings:
    $key_b258 = { e5 2a [2] d7 08 [2] d1 3d [2] ff 3d [2] c0 21 }

  condition:
    any of them
}