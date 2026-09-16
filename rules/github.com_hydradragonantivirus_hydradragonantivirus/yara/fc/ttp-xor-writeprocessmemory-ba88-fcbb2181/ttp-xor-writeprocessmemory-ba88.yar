rule TTP_XOR_WriteProcessMemory_ba88 {
  strings:
    $key_ba88 = { ed fa [2] df d8 [2] d9 ed [2] f7 ed [2] c8 f1 }

  condition:
    any of them
}