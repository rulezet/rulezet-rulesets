rule mpc_sv8: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (SV8)"

    strings:
        $a = {4D 50 43 4B 53 48 0F}

    condition:
       $a at 0
}