rule TTP_XOR_WriteProcessMemory_9fda {
  strings:
    $key_9fda = { c8 a8 [2] fa 8a [2] fc bf [2] d2 bf [2] ed a3 }

  condition:
    any of them
}