#Zpher

**Zpher** es una herramienta de cifrado simétrico escrita en **C# (.NET)**.  
Combina derivación de clave **Argon2id** y cifrado autenticado **AES-GCM**, sellando archivos o carpetas en un contenedor personalizado con extensión **`.7km`** y encabezado **`7KMVAUL7`**.

---

## Características principales

- **Argon2id KDF**: 256 MB de memoria, 3 iteraciones, paralelismo automático según CPU.
  
- **AES-GCM autenticado**: tag de 128 bits, confidencialidad e integridad garantizadas.
  
- **Compresión automática ZIP** para carpetas antes del cifrado.
  
- **Cabecera versionada** (`7KMVAUL7 V1`) con metadatos, parámetros y AAD autenticada.
  
- **Interfaz consola clara** y registro técnico (`.log`).
  
- **Autoextensiones**: `.7km` al cifrar, `.zip` al descifrar.
  
- **Confirmación de contraseña** + cálculo de entropía estimada.
  
- **Cabecera autenticada** para prevenir manipulación o downgrade de parámetros.
  

---

## Uso rápido

Ejecuta el programa y selecciona una opción:

```
Zpher.exe
```

1. Cifrar (archivo o carpeta)
  
2. Descifrar archivo `.7km`
  
3. Manual / Ayuda
  

El resultado cifrado se guardará como `nombreoriginal.7km`.  
Al descifrar, se generará `nombreoriginal.zip`, con opción de descomprimir.

---

## Estructura del formato `.7km`

| Campo | Tamaño | Descripción |
| --- | --- | --- |
| MAGIC | 8 bytes | `7KMVAUL7` (firma del formato) |
| Versión | 1 byte | v1  |
| KDF ID | 1 byte | Argon2id |
| Salt | 16 bytes | Salt aleatorio |
| Parámetros Argon2 | 12 bytes | memKB, iter, lanes |
| Base Nonce | 12 bytes | Nonce inicial |
| AAD Len + AAD | variable | Datos asociados autenticados |
| Bloques cifrados | 1 MiB cada uno | + Tag AES-GCM (16 bytes) |

---

## Fundamentos criptográficos

- **KDF** → Argon2id (memoria-hard, resistente a GPU/ASIC).
  
- **Cifrado** → AES-GCM (modo autenticado con tag de 128 bits).
  
- **Integridad** → Cualquier modificación rompe la autenticación.
  
- **Compatibilidad futura** → Cabecera versionada y parámetros explícitos.
  

---

## DISCLAIMER

Zpher se ha creado con fines **educativos**.  
No está destinado para usos ilícitos.  
El autor no asume responsabilidad por usos indebidos.
  
Puedes usar, copiar, modificar y distribuir libremente el código,  
manteniendo este aviso de licencia y autoría.

---

## Licencia

Licencia **MIT** © 2025 7ekiero <3
> *Privacy means liberty.*
