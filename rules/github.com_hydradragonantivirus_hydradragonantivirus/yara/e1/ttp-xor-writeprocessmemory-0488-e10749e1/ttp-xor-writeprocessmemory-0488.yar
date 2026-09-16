rule TTP_XOR_WriteProcessMemory_0488 {
  strings:
    $key_0488 = { 53 fa [2] 61 d8 [2] 67 ed [2] 49 ed [2] 76 f1 }

  condition:
    any of them
}