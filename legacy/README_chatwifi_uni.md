# Chat WiFi Uni

Chat de escritorio para enviar mensajes entre dos computadoras conectadas a la misma red WiFi,
sin necesidad de internet. Una PC actua como **servidor** y la otra como **cliente**.

## Requisitos

- Python 3.8 o superior
- Tkinter (viene incluido con Python en Windows)
- Ambas PC en la misma red WiFi

## Uso

```bash
python ChatWiFi_Uni.py
```

1. En la **PC 1**: selecciona *Servidor*, anota la IP que aparece y pulsa **Iniciar Servidor**.
2. En la **PC 2**: selecciona *Cliente*, escribe la IP de la PC 1 y pulsa **Conectar**.
3. Ambos deben usar el mismo puerto (por defecto `5000`).

> Si no conecta, revisa el Firewall de Windows: debe permitir Python en redes privadas.

## Estructura

```
ChatWiFi_Uni.py     Aplicacion completa (interfaz + red)
```

## Notas

- La configuracion local se guarda en `.chat_wifi_settings.json`, que esta en `.gitignore`
  porque contiene credenciales. No lo subas al repositorio.
