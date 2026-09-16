rule TTP_XOR_WriteProcessMemory_a388 {
  strings:
    $key_a388 = { f4 fa [2] c6 d8 [2] c0 ed [2] ee ed [2] d1 f1 }

  condition:
    any of them
}