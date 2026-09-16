rule TTP_XOR_WriteProcessMemory_9db8 {
  strings:
    $key_9db8 = { ca ca [2] f8 e8 [2] fe dd [2] d0 dd [2] ef c1 }

  condition:
    any of them
}