rule TTP_XOR_WriteProcessMemory_eddc {
  strings:
    $key_eddc = { ba ae [2] 88 8c [2] 8e b9 [2] a0 b9 [2] 9f a5 }

  condition:
    any of them
}