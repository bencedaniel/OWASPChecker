function getCategories(harvestedIds) {
    return harvestedIds?.categories || harvestedIds || {};
}

function findIdsForSegment(segment, categories) {
    const normalizedSegment = segment.toLowerCase();
    const category = Object.keys(categories).find(
        key => key.toLowerCase() === normalizedSegment
    );
    return category && Array.isArray(categories[category]) ? categories[category] : [];
}

/**
 * Resolves each path parameter from the nearest resource category in the path.
 * Returns null when recon did not collect an ID for any required resource.
 */
export function resolvePathParams(path, harvestedIds) {
    const categories = getCategories(harvestedIds);
    const pathParts = path.split('/').filter(Boolean);
    const replacements = new Map();

    for (let index = 0; index < pathParts.length; index++) {
        const part = pathParts[index];
        const parameterMatch = part.match(/^\{([^}]+)\}$/);
        if (!parameterMatch) continue;

        let ids = [];
        for (let resourceIndex = index - 1; resourceIndex >= 0; resourceIndex--) {
            ids = findIdsForSegment(pathParts[resourceIndex], categories);
            if (ids.length > 0) break;
        }

        if (ids.length === 0) return null;
        replacements.set(parameterMatch[1], ids[0]);
    }

    return path.replace(/\{([^}]+)\}/g, (_, parameterName) =>
        replacements.get(parameterName)
    );
}

export function resolvePathParamCandidates(path, harvestedIds, limit = 50) {
    const categories = getCategories(harvestedIds);
    const pathParts = path.split('/').filter(Boolean);
    const parameterIndexes = pathParts
        .map((part, index) => /^\{[^}]+\}$/.test(part) ? index : -1)
        .filter(index => index !== -1);

    if (parameterIndexes.length === 0) return [path];

    const idsByParameter = parameterIndexes.map(parameterIndex => {
        for (let resourceIndex = parameterIndex - 1; resourceIndex >= 0; resourceIndex--) {
            const ids = findIdsForSegment(pathParts[resourceIndex], categories);
            if (ids.length > 0) return ids;
        }
        return [];
    });

    if (idsByParameter.some(ids => ids.length === 0)) return [];

    return idsByParameter.reduce((paths, ids, parameterIndex) =>
        paths.flatMap(currentPath => ids.map(id => {
            const candidateParts = currentPath.split('/').filter(Boolean);
            candidateParts[parameterIndexes[parameterIndex]] = String(id);
            return `/${candidateParts.join('/')}`;
        }))
    , [path]).slice(0, limit);
}
