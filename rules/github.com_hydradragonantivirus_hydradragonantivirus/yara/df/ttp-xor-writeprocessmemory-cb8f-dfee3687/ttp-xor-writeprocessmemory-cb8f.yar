rule TTP_XOR_WriteProcessMemory_cb8f {
  strings:
    $key_cb8f = { 9c fd [2] ae df [2] a8 ea [2] 86 ea [2] b9 f6 }

  condition:
    any of them
}