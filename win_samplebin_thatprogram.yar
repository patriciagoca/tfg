import "pe"
import "math"

rule win_samplebin_thatprogram
{
    meta:
        description = "TFG - Detección estructural y heuróstica de sample.bin y variantes."
        author = "P.G.C."

    strings:
        // Obligatorias
        $that_program = "!That program cannot"
        $copia_carga = { 8D 35 08 36 40 00 }

        // Alternativas
        $funcion_entorpece_analisis = { 50 8B C1 58 C3 }
        $anti_analysis_call5 = { E8 00 00 00 00 }
        $mz_payload = { 4D 5A }

    condition:
        // Estructura PE
        pe.is_pe and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
        and pe.number_of_sections == 3

        // Obligatorias
        and $that_program
        and $copia_carga

        // Mínimo una opción (entorpece_analisis, antianalisis, (MZ o entropía alta en .data))
        and (
            $funcion_entorpece_analisis
            or
            $anti_analysis_call5
            or
            for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name == ".data"
                and
                (
                    $mz_payload in (
                        pe.sections[i].raw_data_offset ..
                        pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size - 1
                    )
                    or
                    math.entropy(
                        pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size ) > 7.0
                )
            )
        )
}
