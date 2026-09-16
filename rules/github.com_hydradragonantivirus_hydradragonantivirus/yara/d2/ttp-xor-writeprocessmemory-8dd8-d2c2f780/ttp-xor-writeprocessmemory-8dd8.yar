rule TTP_XOR_WriteProcessMemory_8dd8 {
  strings:
    $key_8dd8 = { da aa [2] e8 88 [2] ee bd [2] c0 bd [2] ff a1 }

  condition:
    any of them
}