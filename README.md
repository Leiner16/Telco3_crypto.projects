# Crypto Signature Tool

Este programa es una herramienta de consola para generar pares de claves RSA, firmar mensajes y verificar firmas. Está diseñado para ser usado en ambientes que requieran criptografía básica de clave pública.

## Cómo usar

El programa se ejecuta desde la línea de comandos y proporciona un menú interactivo con las siguientes opciones:

1. **Generar par de claves:** crea un nuevo par de claves RSA (pública y privada) y las almacena en el sistema de archivos.
2. **Firmar mensaje:** permite firmar un mensaje utilizando una clave privada especificada.
3. **Verificar firma:** verifica si una firma dada es válida para un mensaje específico utilizando la clave pública correspondiente.
4. **Salir:** cierra la aplicación.

### Generar un par de claves

Selecciona la opción 1 para generar un nuevo par de claves. Las claves se almacenarán automáticamente en la carpeta `bin/Debug/net8.0/KEYS/` dentro de una nueva subcarpeta única para cada par.
![image](https://github.com/sebaez11/cryptography-lab/assets/64449316/bc78de6a-8f27-4bf3-bdba-ca4c857124e2)

### Firmar un mensaje

Para firmar un mensaje, selecciona la opción 2. Se te pedirá que ingreses el mensaje a firmar y luego la ruta de la clave privada. Puedes especificar la ruta de la clave privada de forma absoluta o relativa. Por ejemplo:

- Ruta absoluta: `C:\Users\x\OneDrive\Escritorio\BLOCKCHAIN-UNILLANOS\crypto.projects\bin\Debug\net8.0\KEYS\26d2b60f-808c-4ade-b825-0e62b1b9d555\privateKey.xml`
- Ruta relativa: `26d2b60f-808c-4ade-b825-0e62b1b9d555\privateKey.xml`

### Verificar una firma

Para verificar una firma, selecciona la opción 3. El programa automáticamente usará el mensaje guardado anteriormente en `mensaje.txt` y te pedirá la ruta de la clave pública para la verificación. Al igual que con la firma, puedes especificar la ruta de la clave pública de forma absoluta o relativa.

## Almacenamiento de claves

Las claves generadas se almacenan en `bin/Debug/net8.0/KEYS/`. Cada par de claves se coloca en una carpeta separada dentro de `KEYS` para su organización y referencia.

## Notas adicionales

- Asegúrate de que el entorno de ejecución tiene los permisos necesarios para crear y escribir en la ubicación de almacenamiento de las claves.
- Cuando se proporcionan rutas relativas para la clave privada o pública, el programa las resolverá en relación con el directorio actual de trabajo.
