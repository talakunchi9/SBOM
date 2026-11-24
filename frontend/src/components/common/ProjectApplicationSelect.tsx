import React, { useEffect, useRef, useState } from 'react';
import { ApiError, createCatalogApplication, createCatalogProject, type CatalogRecord } from '../../api/client';
import { SearchableSelect } from './SearchableSelect';
import { useCatalogApplications, useCatalogProjects } from '../../hooks/useCatalogOptions';

export interface ProjectApplicationValue {
  project: CatalogRecord | null;
  application: CatalogRecord | null;
}

interface ProjectApplicationSelectProps {
  value: ProjectApplicationValue;
  onChange: (next: ProjectApplicationValue) => void;
  required?: boolean;
  variant?: 'scan' | 'form';
  projectLabel?: React.ReactNode;
  applicationLabel?: React.ReactNode;
  projectHint?: string;
  applicationHint?: string;
  className?: string;
  allowCreate?: boolean;
  freeform?: boolean;
}

export const ProjectApplicationSelect: React.FC<ProjectApplicationSelectProps> = ({
  value,
  onChange,
  required = true,
  variant = 'form',
  projectLabel = 'Project Name',
  applicationLabel = 'Application / Service',
  projectHint,
  applicationHint,
  className,
  allowCreate = false,
  freeform = true,
}) => {
  const projects = useCatalogProjects();
  const applications = useCatalogApplications(value.project?.id || null);
  const projectKey = value.project ? `${value.project.id || ''}:${value.project.name || ''}` : '';
  const lastProject = useRef(projectKey);
  const [creatingProject, setCreatingProject] = useState(false);
  const [creatingApplication, setCreatingApplication] = useState(false);
  const [projectError, setProjectError] = useState<string | null>(null);
  const [applicationError, setApplicationError] = useState<string | null>(null);

  useEffect(() => {
    if (lastProject.current === projectKey) return;
    const oldKey = lastProject.current;
    lastProject.current = projectKey;
    const oldId = oldKey.split(':')[0];
    const newId = projectKey.split(':')[0];
    if (oldId && newId && oldId !== newId && value.application) {
      onChange({ project: value.project, application: null });
    }
  }, [onChange, value.application, value.project, projectKey]);

  const applicationDisabled = !value.project || !value.project.name?.trim();
  const applicationPlaceholder = applicationDisabled
    ? 'Select an Application First'
    : applications.loading
      ? 'Loading modules…'
      : 'Select or type a module';
  const applicationEmpty = applications.error
    ? applications.error
    : 'No matching modules found';

  const addProject = async (name: string) => {
    setCreatingProject(true);
    setProjectError(null);
    try {
      const created = await createCatalogProject({ name });
      projects.reload();
      onChange({ project: { id: created.id, name: created.name }, application: null });
    } catch (error) {
      setProjectError(error instanceof ApiError ? error.message : 'Could not add project.');
      throw error;
    } finally {
      setCreatingProject(false);
    }
  };

  const addApplication = async (name: string) => {
    if (!value.project?.id) return;
    setCreatingApplication(true);
    setApplicationError(null);
    try {
      const created = await createCatalogApplication(value.project.id, name);
      applications.reload();
      onChange({
        project: value.project,
        application: { id: created.id, name: created.name, project_id: created.project_id },
      });
    } catch (error) {
      setApplicationError(error instanceof ApiError ? error.message : 'Could not add application/service.');
      throw error;
    } finally {
      setCreatingApplication(false);
    }
  };

  return (
    <>
      <div className={className}>
        <SearchableSelect
          variant={variant}
          label={projectLabel}
          required={required}
          value={value.project}
          options={projects.items}
          loading={projects.loading}
          creating={creatingProject}
          allowCreate={allowCreate}
          freeform={freeform}
          error={projectError || projects.error}
          emptyMessage={projects.error || 'No matching applications found'}
          placeholder="Select or type an application name"
          hint={projectHint}
          hasMore={projects.hasMore}
          onLoadMore={projects.loadMore}
          onQueryChange={projects.setQuery}
          onOpen={projects.reload}
          onCreate={allowCreate ? addProject : undefined}
          onChange={(project) => {
            setProjectError(null);
            const isDifferentProject = project?.id && value.project?.id && project.id !== value.project.id;
            onChange({
              project,
              application: isDifferentProject ? null : value.application,
            });
          }}
        />
      </div>
      <div className={className}>
        <SearchableSelect
          variant={variant}
          label={applicationLabel}
          required={required}
          value={value.application}
          options={applications.items}
          loading={applications.loading}
          creating={creatingApplication}
          allowCreate={allowCreate}
          freeform={freeform}
          disabled={applicationDisabled}
          error={applicationError || applications.error}
          emptyMessage={applicationEmpty}
          placeholder={applicationPlaceholder}
          disabledPlaceholder={applicationPlaceholder}
          hint={applicationHint}
          hasMore={applications.hasMore}
          onLoadMore={applications.loadMore}
          onQueryChange={applications.setQuery}
          onCreate={allowCreate ? addApplication : undefined}
          onChange={(application) => {
            setApplicationError(null);
            onChange({ project: value.project, application });
          }}
        />
      </div>
    </>
  );
};
