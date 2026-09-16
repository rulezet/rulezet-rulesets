rule TTP_XOR_WriteProcessMemory_fdda {
  strings:
    $key_fdda = { aa a8 [2] 98 8a [2] 9e bf [2] b0 bf [2] 8f a3 }

  condition:
    any of them
}