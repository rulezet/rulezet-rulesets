rule TTP_XOR_WriteProcessMemory_cb87 {
  strings:
    $key_cb87 = { 9c f5 [2] ae d7 [2] a8 e2 [2] 86 e2 [2] b9 fe }

  condition:
    any of them
}