rule mpc_sv7: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (SV7)"

    strings:
        $a = {4D 50 2B 07}

    condition:
       $a at 0
}