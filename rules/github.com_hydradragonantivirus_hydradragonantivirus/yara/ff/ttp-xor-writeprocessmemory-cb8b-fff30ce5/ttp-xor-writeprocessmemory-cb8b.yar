rule TTP_XOR_WriteProcessMemory_cb8b {
  strings:
    $key_cb8b = { 9c f9 [2] ae db [2] a8 ee [2] 86 ee [2] b9 f2 }

  condition:
    any of them
}