/**
 * @since 1.0.0
 */

/**
 * Says a simple "Hello!" to absolutely anyone except Nik.
 *
 * @since 1.0.0
 */
export const say = (name: string) => name === "Nik" ? `Servas Nik!` : `Hello ${name}!`
