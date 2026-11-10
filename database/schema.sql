# Esquema real exportado de MariaDB 11.4 (10-11-2026).
# SOLO estructura: sin registros, claves, hashes de usuario ni correos.
# Crear una base vacía previamente e importar este archivo a ella.

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `phishguardai`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `acciones_analista`
--

CREATE TABLE `acciones_analista` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `correo_id` bigint(20) UNSIGNED NOT NULL,
  `usuario_id` bigint(20) UNSIGNED NOT NULL,
  `tipo` varchar(40) NOT NULL,
  `detalle` varchar(1000) DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp()
) ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `correos_analizados`
--

CREATE TABLE `correos_analizados` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `uidvalidity` varchar(40) NOT NULL,
  `uid` bigint(20) UNSIGNED NOT NULL,
  `solicitante_email` varchar(254) NOT NULL,
  `asunto` varchar(500) NOT NULL,
  `clasificacion` varchar(40) NOT NULL,
  `riesgo` tinyint(3) UNSIGNED NOT NULL,
  `attack_tecnica` varchar(12) DEFAULT NULL,
  `attack_evidencia` varchar(500) DEFAULT NULL,
  `resumen` text DEFAULT NULL,
  `recomendacion` text DEFAULT NULL,
  `tokens_entrada` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `tokens_salida` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `estado_envio` varchar(20) NOT NULL DEFAULT 'PENDIENTE',
  `fecha_analisis` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_envio` datetime DEFAULT NULL,
  `remitente_original_dominio` varchar(253) DEFAULT NULL,
  `remitente_original_fuente` varchar(50) DEFAULT NULL,
  `remitente_geo_ip` varchar(45) DEFAULT NULL,
  `remitente_geo_pais` varchar(100) DEFAULT NULL,
  `remitente_geo_pais_codigo` char(2) DEFAULT NULL,
  `remitente_geo_asn` varchar(30) DEFAULT NULL,
  `remitente_geo_proveedor` varchar(255) DEFAULT NULL,
  `remitente_geo_estado` varchar(20) NOT NULL DEFAULT 'PENDIENTE',
  `remitente_geo_fecha` datetime DEFAULT NULL,
  `auth_spf` varchar(20) NOT NULL DEFAULT 'NO_VERIFICADO',
  `auth_dkim` varchar(20) NOT NULL DEFAULT 'NO_VERIFICADO',
  `auth_dmarc` varchar(20) NOT NULL DEFAULT 'NO_VERIFICADO',
  `auth_fuente` varchar(60) NOT NULL DEFAULT 'NO_VERIFICADO',
  `auth_confiable` tinyint(1) NOT NULL DEFAULT 0,
  `auth_nota` varchar(500) DEFAULT NULL,
  `auth_fecha` datetime DEFAULT NULL,
  `dns_spf_estado` varchar(25) NOT NULL DEFAULT 'PENDIENTE',
  `dns_spf_registro` text DEFAULT NULL,
  `dns_dmarc_estado` varchar(25) NOT NULL DEFAULT 'PENDIENTE',
  `dns_dmarc_politica` varchar(20) DEFAULT NULL,
  `dns_dmarc_registro` text DEFAULT NULL,
  `dns_fecha_consulta` datetime DEFAULT NULL,
  `auth_original_tipo` varchar(50) NOT NULL DEFAULT 'SIN_EVALUAR',
  `auth_original_dominio_citado` varchar(253) DEFAULT NULL,
  `auth_original_campos_citados` varchar(80) DEFAULT NULL,
  `auth_original_auth_citada` tinyint(1) NOT NULL DEFAULT 0,
  `auth_original_fuente` varchar(60) NOT NULL DEFAULT 'SIN_EVALUAR'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `correo_urls`
--

CREATE TABLE `correo_urls` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `correo_id` bigint(20) UNSIGNED NOT NULL,
  `vt_url_id` bigint(20) UNSIGNED NOT NULL,
  `fecha_registro` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `eventos_sistema`
--

CREATE TABLE `eventos_sistema` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `correo_id` bigint(20) UNSIGNED DEFAULT NULL,
  `actor_email` varchar(254) DEFAULT NULL,
  `tipo` varchar(60) NOT NULL,
  `detalle` varchar(1000) DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `indicadores_phishing`
--

CREATE TABLE `indicadores_phishing` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `correo_id` bigint(20) UNSIGNED NOT NULL,
  `descripcion` varchar(1000) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tokens_activacion`
--

CREATE TABLE `tokens_activacion` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `usuario_id` bigint(20) UNSIGNED NOT NULL,
  `token_hash` char(64) NOT NULL,
  `expira` datetime NOT NULL,
  `usado` datetime DEFAULT NULL,
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `email` varchar(254) NOT NULL,
  `nombre` varchar(120) DEFAULT NULL,
  `password_hash` varchar(255) NOT NULL,
  `rol` varchar(20) NOT NULL DEFAULT 'EMPLEADO',
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp(),
  `ultimo_acceso` datetime DEFAULT NULL
) ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `vt_urls`
--

CREATE TABLE `vt_urls` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `url_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `url` text NOT NULL,
  `estado` enum('PENDIENTE','PROCESANDO','COMPLETADO','SIN_REPORTE','ERROR','OMITIDA') NOT NULL DEFAULT 'PENDIENTE',
  `vt_id` varchar(100) DEFAULT NULL,
  `malicious` int(10) UNSIGNED DEFAULT NULL,
  `suspicious` int(10) UNSIGNED DEFAULT NULL,
  `harmless` int(10) UNSIGNED DEFAULT NULL,
  `undetected` int(10) UNSIGNED DEFAULT NULL,
  `respuesta_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`respuesta_json`)),
  `intentos` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `proximo_intento` datetime DEFAULT NULL,
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_consulta` datetime DEFAULT NULL,
  `fecha_actualizacion` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `geo_dominio` varchar(253) DEFAULT NULL,
  `geo_ip` varchar(45) DEFAULT NULL,
  `geo_pais` varchar(100) DEFAULT NULL,
  `geo_pais_codigo` char(2) DEFAULT NULL,
  `geo_asn` varchar(30) DEFAULT NULL,
  `geo_proveedor` varchar(255) DEFAULT NULL,
  `geo_estado` varchar(20) NOT NULL DEFAULT 'PENDIENTE',
  `geo_fecha_consulta` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `acciones_analista`
--
ALTER TABLE `acciones_analista`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_acciones_correo_fecha` (`correo_id`,`fecha`),
  ADD KEY `idx_acciones_usuario` (`usuario_id`);

--
-- Indices de la tabla `correos_analizados`
--
ALTER TABLE `correos_analizados`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_mensaje` (`uidvalidity`,`uid`),
  ADD KEY `idx_fecha` (`fecha_analisis`),
  ADD KEY `idx_clasificacion` (`clasificacion`),
  ADD KEY `idx_riesgo` (`riesgo`),
  ADD KEY `idx_solicitante` (`solicitante_email`),
  ADD KEY `idx_attack_tecnica` (`attack_tecnica`),
  ADD KEY `idx_remitente_geo_pais` (`remitente_geo_pais_codigo`),
  ADD KEY `idx_remitente_geo_estado` (`remitente_geo_estado`),
  ADD KEY `idx_dns_spf_estado` (`dns_spf_estado`),
  ADD KEY `idx_dns_dmarc_estado` (`dns_dmarc_estado`),
  ADD KEY `idx_auth_original_tipo` (`auth_original_tipo`);

--
-- Indices de la tabla `correo_urls`
--
ALTER TABLE `correo_urls`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_correo_vt_url` (`correo_id`,`vt_url_id`),
  ADD KEY `fk_correo_urls_vt` (`vt_url_id`);

--
-- Indices de la tabla `eventos_sistema`
--
ALTER TABLE `eventos_sistema`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_tipo_fecha` (`tipo`,`fecha`),
  ADD KEY `idx_fecha_evento` (`fecha`),
  ADD KEY `fk_eventos_correo` (`correo_id`);

--
-- Indices de la tabla `indicadores_phishing`
--
ALTER TABLE `indicadores_phishing`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_indicadores_correo` (`correo_id`);

--
-- Indices de la tabla `tokens_activacion`
--
ALTER TABLE `tokens_activacion`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_tokens_activacion_hash` (`token_hash`),
  ADD KEY `idx_tokens_activacion_usuario` (`usuario_id`,`fecha_creacion`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_usuarios_email` (`email`);

--
-- Indices de la tabla `vt_urls`
--
ALTER TABLE `vt_urls`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_vt_url_sha256` (`url_sha256`),
  ADD KEY `idx_vt_cola` (`estado`,`proximo_intento`,`fecha_creacion`),
  ADD KEY `idx_geo_estado` (`geo_estado`),
  ADD KEY `idx_geo_pais` (`geo_pais_codigo`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `acciones_analista`
--
ALTER TABLE `acciones_analista`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `correos_analizados`
--
ALTER TABLE `correos_analizados`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `correo_urls`
--
ALTER TABLE `correo_urls`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `eventos_sistema`
--
ALTER TABLE `eventos_sistema`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `indicadores_phishing`
--
ALTER TABLE `indicadores_phishing`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tokens_activacion`
--
ALTER TABLE `tokens_activacion`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `vt_urls`
--
ALTER TABLE `vt_urls`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `acciones_analista`
--
ALTER TABLE `acciones_analista`
  ADD CONSTRAINT `fk_acciones_correo` FOREIGN KEY (`correo_id`) REFERENCES `correos_analizados` (`id`),
  ADD CONSTRAINT `fk_acciones_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `correo_urls`
--
ALTER TABLE `correo_urls`
  ADD CONSTRAINT `fk_correo_urls_correo` FOREIGN KEY (`correo_id`) REFERENCES `correos_analizados` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_correo_urls_vt` FOREIGN KEY (`vt_url_id`) REFERENCES `vt_urls` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `eventos_sistema`
--
ALTER TABLE `eventos_sistema`
  ADD CONSTRAINT `fk_eventos_correo` FOREIGN KEY (`correo_id`) REFERENCES `correos_analizados` (`id`) ON DELETE SET NULL;

--
-- Filtros para la tabla `indicadores_phishing`
--
ALTER TABLE `indicadores_phishing`
  ADD CONSTRAINT `fk_indicadores_correo` FOREIGN KEY (`correo_id`) REFERENCES `correos_analizados` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `tokens_activacion`
--
ALTER TABLE `tokens_activacion`
  ADD CONSTRAINT `fk_tokens_activacion_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
