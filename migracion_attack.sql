-- Ejecutar UNA SOLA VEZ sobre la base existente (no borra datos).
ALTER TABLE correos_analizados
  ADD COLUMN attack_tecnica VARCHAR(12) NULL AFTER riesgo,
  ADD COLUMN attack_evidencia VARCHAR(500) NULL AFTER attack_tecnica,
  ADD INDEX idx_attack_tecnica (attack_tecnica);

-- Técnicas más frecuentes (solo las asignadas):
SELECT attack_tecnica, COUNT(*) AS cantidad
FROM correos_analizados
WHERE attack_tecnica IS NOT NULL
GROUP BY attack_tecnica ORDER BY cantidad DESC;
