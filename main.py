# tarea.py

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, List
import jwt
from datetime import datetime, timedelta

app = FastAPI()
security = HTTPBearer()

# Simulación de base de usuarios con tokens, roles y contraseñas
fake_users_db = {
    "alice": {"username": "alice", "password": "password123", "role": "Orquestador"},
    "bob": {"username": "bob", "password": "password456", "role": "Administrador"},
    "charlie": {"username": "charlie", "password": "password789", "role": "Usuario"}
}

# Simulación de base de servicios disponibles
fake_services = {
    "servicio-envio": {"nombre": "Servicio de Envío", "estado": "activo"},
    "servicio-pago": {"nombre": "Servicio de Pago", "estado": "mantenimiento"},
    "servicio-stock": {"nombre": "Servicio de Stock", "estado": "activo"}
}

# Variable simulada para almacenar reglas de orquestación
reglas_orquestacion = []

# Diccionario de permisos por rol
role_permissions = {
    "Administrador": ["servicio-envio", "servicio-pago", "servicio-stock"],
    "Orquestador": ["servicio-envio", "servicio-pago"],
    "Usuario": ["servicio-envio"]
}

# ------------------------
# Modelos de datos
# ------------------------

class OrquestarRequest(BaseModel):
    servicio_destino: str
    parametros_adicionales: Optional[Dict[str, str]] = {}

class NuevoServicioRequest(BaseModel):
    nombre: str
    descripcion: str
    endpoints: List[str]

class ReglaOrquestacion(BaseModel):
    servicio_origen: str
    servicio_destino: str
    condicion: Optional[str] = None
    accion: Optional[str] = None

class ActualizarReglasRequest(BaseModel):
    reglas: List[ReglaOrquestacion]

class AuthRequest(BaseModel):
    nombre_usuario: str
    contrasena: str

class Token(BaseModel):
    access_token: str
    token_type: str

class AutorizarAccesoRequest(BaseModel):
    recursos: List[str]
    rol_usuario: str
# ------------------------
# Función de autenticación
# ------------------------

SECRET_KEY = "mi_clave_secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(auth_request: AuthRequest):
    user = fake_users_db.get(auth_request.nombre_usuario)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nombre de usuario no válido"
        )
    
    if user["password"] != auth_request.contrasena:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta"
        )
    
    return user

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = fake_users_db.get(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido o no proporcionado"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ha expirado"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    return user

# ------------------------
# Endpoints
# ------------------------

@app.post("/autenticar-usuario")
def autenticar_usuario(auth_request: AuthRequest):
    user = authenticate_user(auth_request)

    # Crear un token JWT
    access_token = create_access_token(data={"sub": user["username"]})

    return {
        "mensaje": "Usuario autenticado correctamente",
        "usuario": user["username"],
        "rol": user["role"],
        "access_token": access_token
    }
    
    # Verificar si la contraseña es correcta
    if user["password"] != request.contrasena:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta"
        )

    # Crear el token de acceso (JWT)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": request.nombre_usuario, "role": user["role"]},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/orquestar")
def orquestar(
    request: OrquestarRequest,
    user: dict = Depends(get_current_user)
):
    if user["role"] not in ["Orquestador", "Administrador"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene permisos para orquestar servicios"
        )

    return {
        "mensaje": "Orquestación iniciada correctamente",
        "usuario": user["username"],
        "rol": user["role"],
        "servicio_destino": request.servicio_destino,
        "parametros_adicionales": request.parametros_adicionales
    }

@app.get("/informacion-servicio/{id}")
def obtener_informacion_servicio(id: str, user: dict = Depends(get_current_user)):
    servicio = fake_services.get(id)
    if not servicio:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servicio no encontrado"
        )

    return {
        "mensaje": "Información del servicio obtenida correctamente",
        "usuario": user["username"],
        "servicio_id": id,
        "informacion": servicio
    }

@app.post("/registrar-servicio")
def registrar_servicio(
    request: NuevoServicioRequest,
    user: dict = Depends(get_current_user)
):
    if user["role"] != "Administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo administradores pueden registrar servicios"
        )

    service_id = request.nombre.lower().replace(" ", "-")

    if service_id in fake_services:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El servicio ya existe"
        )

    fake_services[service_id] = {
        "nombre": request.nombre,
        "descripcion": request.descripcion,
        "endpoints": request.endpoints,
        "estado": "registrado"
    }

    return {
        "mensaje": "Servicio registrado correctamente",
        "id_servicio": service_id,
        "datos": fake_services[service_id]
    }

@app.put("/actualizar-reglas-orquestacion")
def actualizar_reglas_orquestacion(
    request: ActualizarReglasRequest,
    user: dict = Depends(get_current_user)
):
    if user["role"] != "Orquestador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo los usuarios con rol 'Orquestador' pueden actualizar reglas de orquestación"
        )

    global reglas_orquestacion
    reglas_orquestacion = request.reglas

    return {
        "mensaje": "Reglas de orquestación actualizadas correctamente",
        "usuario": user["username"],
        "nuevas_reglas": reglas_orquestacion
    }

@app.post("/autorizar-acceso")
def autorizar_acceso(
    request: AutorizarAccesoRequest,
    user: dict = Depends(get_current_user)  # Usamos el token para verificar la identidad
):
    # Verificamos si el rol del usuario tiene acceso a los recursos solicitados
    permisos_rol = role_permissions.get(request.rol_usuario)

    if permisos_rol is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Rol no reconocido"
        )
    
    recursos_no_permitidos = [recurso for recurso in request.recursos if recurso not in permisos_rol]

    if recursos_no_permitidos:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado a los recursos: {', '.join(recursos_no_permitidos)}"
        )

    return {
        "mensaje": "Acceso autorizado a los recursos solicitados",
        "usuario": user["username"],
        "recursos_autorizados": request.recursos
    }