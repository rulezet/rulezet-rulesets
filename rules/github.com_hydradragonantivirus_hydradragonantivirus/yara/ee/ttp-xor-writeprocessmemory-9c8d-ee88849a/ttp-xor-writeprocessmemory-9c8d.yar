rule TTP_XOR_WriteProcessMemory_9c8d {
  strings:
    $key_9c8d = { cb ff [2] f9 dd [2] ff e8 [2] d1 e8 [2] ee f4 }

  condition:
    any of them
}