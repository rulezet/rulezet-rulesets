rule TTP_XOR_WriteProcessMemory_f9a8 {
  strings:
    $key_f9a8 = { ae da [2] 9c f8 [2] 9a cd [2] b4 cd [2] 8b d1 }

  condition:
    any of them
}