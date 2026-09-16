rule TTP_XOR_WriteProcessMemory_8db6 {
  strings:
    $key_8db6 = { da c4 [2] e8 e6 [2] ee d3 [2] c0 d3 [2] ff cf }

  condition:
    any of them
}