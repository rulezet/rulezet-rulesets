rule TTP_XOR_WriteProcessMemory_a3d8 {
  strings:
    $key_a3d8 = { f4 aa [2] c6 88 [2] c0 bd [2] ee bd [2] d1 a1 }

  condition:
    any of them
}