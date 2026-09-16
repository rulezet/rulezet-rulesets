rule TTP_XOR_WriteProcessMemory_58ba {
  strings:
    $key_58ba = { 0f c8 [2] 3d ea [2] 3b df [2] 15 df [2] 2a c3 }

  condition:
    any of them
}